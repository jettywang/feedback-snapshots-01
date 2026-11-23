"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""
import logging

from cfn_policy_validator.release.approval_report import ApprovalReport
from cfn_policy_validator.release.gate import ReleaseGate
from cfn_policy_validator.release.policy_version_resolver import PolicyVersionResolver

LOGGER = logging.getLogger("cfn-policy-validator")


def evaluate_role_release(roles, region, approval_report_path=None, approval_report=None, iam_client=None):
	"""
	Convenience entry point that evaluates parsed roles against a version-pinned approval report.

	@param roles: roles returned by IdentityParser.parse
	@param region: region used to build the IAM client when a version must be resolved
	@param approval_report_path: path to a JSON approval report (used when approval_report is not given)
	@param approval_report: an already-constructed ApprovalReport, taking precedence over the path
	@param iam_client: optional pre-built IAM client, primarily for testing
	@return: a ReleaseGateReport whose is_release_approved reflects both each role's resolved
		managed policy version and the approval basis recorded in the report.
	"""
	if approval_report is None:
		if approval_report_path is None:
			raise ValueError('Either approval_report or approval_report_path must be provided.')
		approval_report = ApprovalReport.load(approval_report_path)

	resolver = PolicyVersionResolver(region, iam_client=iam_client)
	return ReleaseGate(approval_report, resolver).evaluate(roles)
